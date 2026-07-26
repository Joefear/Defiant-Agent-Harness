"""Durable, expiring, action-bound approval queue."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..contracts import (
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    new_id,
    utc_now,
)
from ..money import ZERO, MoneyLike, money, money_text
from ..persistence import atomic_write_json, exclusive_file_lock, read_json

APPROVAL_STATUSES = {
    "pending",
    "approved",
    "rejected",
    "expired",
    "executing",
    "consumed",
}


def _parse(ts: str) -> datetime:
    try:
        value = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ApprovalError(f"invalid approval timestamp: {ts!r}") from exc
    if value.tzinfo is None:
        raise ApprovalError("approval timestamps must be timezone-aware")
    return value


@dataclass
class PendingApproval:
    action_id: str
    request_id: str
    tool_name: str
    target: str
    payload_hash: str
    authorization_hash: str
    payload_preview: str
    approval_scope: str
    reason: str
    policy_ids: list[str] = field(default_factory=list)
    expires_at: str = ""
    created_at: str = field(default_factory=utc_now)
    approval_id: str = field(default_factory=lambda: new_id("apr"))
    status: str = "pending"
    decided_by: str | None = None
    decided_at: str | None = None
    note: str = ""
    reserved_usd: str = "0"
    action_snapshot: dict[str, Any] | None = None
    request_snapshot: dict[str, Any] | None = None
    decision_snapshot: dict[str, Any] | None = None
    execution_record_id: str = ""
    consumed_at: str | None = None

    def __post_init__(self) -> None:
        if self.status not in APPROVAL_STATUSES:
            raise ApprovalError(f"invalid approval status: {self.status}")
        for name in ("action_id", "request_id", "tool_name", "approval_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ApprovalError(f"{name} must be non-empty")
        self.reserved_usd = money_text(
            money(self.reserved_usd, field_name="reserved_usd")
        )

    def is_expired(self, now: datetime | None = None) -> bool:
        if not self.expires_at:
            return False
        return (now or datetime.now(timezone.utc)) >= _parse(self.expires_at)

    def held_action(self) -> ProposedAction:
        if self.action_snapshot is None:
            raise ApprovalError(
                f"approval {self.approval_id} has no durable action snapshot"
            )
        return ProposedAction.from_dict(self.action_snapshot)

    def held_request(self) -> HarnessRequest:
        if self.request_snapshot is None:
            raise ApprovalError(
                f"approval {self.approval_id} has no durable request snapshot"
            )
        return HarnessRequest.from_dict(self.request_snapshot)

    def held_decision(self) -> GuardrailDecision:
        if self.decision_snapshot is None:
            raise ApprovalError(
                f"approval {self.approval_id} has no durable decision snapshot"
            )
        return GuardrailDecision.from_dict(self.decision_snapshot)


class ApprovalError(RuntimeError):
    pass


class ApprovalStore:
    def __init__(self, path: str | Path, default_ttl_minutes: int = 60):
        if default_ttl_minutes <= 0:
            raise ValueError("default_ttl_minutes must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.default_ttl_minutes = default_ttl_minutes
        if not self.path.exists():
            with exclusive_file_lock(self.path):
                if not self.path.exists():
                    self._write_all({})
        self._read_all()

    # -- persistence --------------------------------------------------

    def _read_all(self) -> dict[str, dict]:
        data = read_json(self.path)
        for approval_id, raw in data.items():
            if not isinstance(raw, dict):
                raise ApprovalError(f"approval {approval_id} is not an object")
            PendingApproval(**raw)
        return data

    def _write_all(self, data: dict[str, dict]) -> None:
        atomic_write_json(self.path, data)

    def _save(self, approval: PendingApproval) -> None:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            data[approval.approval_id] = asdict(approval)
            self._write_all(data)

    # -- api ----------------------------------------------------------

    def create(
        self,
        action: ProposedAction,
        decision_reason: str,
        approval_scope: str,
        policy_ids: list[str],
        ttl_minutes: int | None = None,
        *,
        request: HarnessRequest | None = None,
        decision: GuardrailDecision | None = None,
        reserved_usd: MoneyLike = ZERO,
    ) -> PendingApproval:
        ttl = ttl_minutes if ttl_minutes is not None else self.default_ttl_minutes
        if ttl <= 0:
            raise ApprovalError("approval TTL must be positive")
        expires = datetime.now(timezone.utc) + timedelta(minutes=ttl)
        pending = PendingApproval(
            action_id=action.action_id,
            request_id=action.request_id,
            tool_name=action.tool_name,
            target=action.target,
            payload_hash=action.payload_hash,
            authorization_hash=action.authorization_hash,
            payload_preview=_preview(action.payload),
            approval_scope=approval_scope,
            reason=decision_reason,
            policy_ids=list(policy_ids),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
            reserved_usd=money_text(reserved_usd),
            action_snapshot=action.to_dict(),
            request_snapshot=request.to_dict() if request else None,
            decision_snapshot=decision.to_dict() if decision else None,
        )
        with exclusive_file_lock(self.path):
            data = self._read_all()
            if any(
                raw.get("action_id") == action.action_id
                and raw.get("status") in {"pending", "approved", "executing"}
                for raw in data.values()
            ):
                raise ApprovalError(
                    f"action {action.action_id} already has an active approval"
                )
            data[pending.approval_id] = asdict(pending)
            self._write_all(data)
        return pending

    def get(self, approval_id: str) -> PendingApproval | None:
        raw = self._read_all().get(approval_id)
        return PendingApproval(**raw) if raw else None

    def list_pending(self) -> list[PendingApproval]:
        self.expire_due()
        return sorted(
            (
                PendingApproval(**raw)
                for raw in self._read_all().values()
                if raw.get("status") == "pending"
            ),
            key=lambda approval: approval.created_at,
        )

    def list_actionable(self) -> list[PendingApproval]:
        self.expire_due()
        return sorted(
            (
                PendingApproval(**raw)
                for raw in self._read_all().values()
                if raw.get("status") in {"pending", "approved", "executing"}
            ),
            key=lambda approval: approval.created_at,
        )

    def expire_due(self, now: datetime | None = None) -> list[PendingApproval]:
        expired: list[PendingApproval] = []
        with exclusive_file_lock(self.path):
            data = self._read_all()
            changed = False
            for approval_id, raw in data.items():
                approval = PendingApproval(**raw)
                if approval.status in {"pending", "approved"} and approval.is_expired(
                    now
                ):
                    approval.status = "expired"
                    approval.consumed_at = utc_now()
                    data[approval_id] = asdict(approval)
                    expired.append(approval)
                    changed = True
            if changed:
                self._write_all(data)
        return expired

    def decide(
        self,
        approval_id: str,
        approved: bool,
        decided_by: str,
        note: str = "",
    ) -> PendingApproval:
        if not isinstance(decided_by, str) or not decided_by.strip():
            raise ApprovalError("decided_by must be non-empty")
        with exclusive_file_lock(self.path):
            data = self._read_all()
            raw = data.get(approval_id)
            if raw is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            approval = PendingApproval(**raw)
            if approval.status != "pending":
                raise ApprovalError(
                    f"approval {approval_id} is already {approval.status}; "
                    "approvals are single-use"
                )
            if approval.is_expired():
                approval.status = "expired"
                approval.consumed_at = utc_now()
                data[approval_id] = asdict(approval)
                self._write_all(data)
                raise ApprovalError(
                    f"approval {approval_id} expired at {approval.expires_at}"
                )
            approval.status = "approved" if approved else "rejected"
            approval.decided_by = decided_by
            approval.decided_at = utc_now()
            approval.note = note
            if not approved:
                approval.consumed_at = approval.decided_at
            data[approval_id] = asdict(approval)
            self._write_all(data)
            return approval

    def validate_for(
        self,
        approval_id: str,
        action: ProposedAction,
    ) -> PendingApproval:
        approval = self.get(approval_id)
        if approval is None:
            raise ApprovalError(f"unknown approval {approval_id}")
        if approval.status not in {"approved", "executing"}:
            raise ApprovalError(
                f"approval {approval_id} is {approval.status}, not approved"
            )
        if approval.is_expired() and approval.status != "executing":
            raise ApprovalError(
                f"approval {approval_id} expired at {approval.expires_at}"
            )
        if approval.action_id != action.action_id:
            raise ApprovalError("approval does not belong to this action")
        if approval.authorization_hash != action.authorization_hash:
            raise ApprovalError("action changed after approval -- the approval is void")
        return approval

    def begin_execution(
        self,
        approval_id: str,
        action: ProposedAction,
    ) -> PendingApproval:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            raw = data.get(approval_id)
            if raw is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            approval = PendingApproval(**raw)
            if approval.status != "approved":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executable"
                )
            if approval.is_expired():
                approval.status = "expired"
                approval.consumed_at = utc_now()
                data[approval_id] = asdict(approval)
                self._write_all(data)
                raise ApprovalError(
                    f"approval {approval_id} expired at {approval.expires_at}"
                )
            if approval.action_id != action.action_id:
                raise ApprovalError("approval does not belong to this action")
            if approval.authorization_hash != action.authorization_hash:
                raise ApprovalError("action changed after approval")
            approval.status = "executing"
            data[approval_id] = asdict(approval)
            self._write_all(data)
            return approval

    def mark_consumed(
        self,
        approval_id: str,
        execution_record_id: str,
    ) -> PendingApproval:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            raw = data.get(approval_id)
            if raw is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            approval = PendingApproval(**raw)
            if approval.status != "executing":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executing"
                )
            approval.status = "consumed"
            approval.execution_record_id = execution_record_id
            approval.consumed_at = utc_now()
            data[approval_id] = asdict(approval)
            self._write_all(data)
            return approval


def _preview(payload: dict, limit: int = 400) -> str:
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"
