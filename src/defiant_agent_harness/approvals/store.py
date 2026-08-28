"""Durable, expiring, action-bound approval queue."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..contracts import (
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    authority_snapshot_and_sha256_of,
    new_id,
    utc_now,
)
from ..frozen_snapshot import freeze_snapshot, thaw_snapshot
from ..limits import MAX_APPROVAL_STATE_BYTES
from ..money import ZERO, MoneyLike, money, money_text
from ..operator_identity import (
    DECISION_PURPOSE,
    RECONCILIATION_PURPOSE,
    OperatorIdentityError,
    OperatorIdentityStatus,
    OperatorTrustPolicy,
    unsigned_status,
)
from ..persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    prepare_storage_root,
    read_json,
)

_MAX_STATE_BYTES = MAX_APPROVAL_STATE_BYTES

_APPROVAL_FIELDS = {
    "action_id",
    "request_id",
    "tool_name",
    "target",
    "payload_hash",
    "authorization_hash",
    "payload_preview",
    "approval_scope",
    "reason",
    "policy_ids",
    "expires_at",
    "created_at",
    "approval_id",
    "status",
    "decided_by",
    "decided_at",
    "note",
    "decision_attestation",
    "reserved_usd",
    "action_snapshot",
    "request_snapshot",
    "decision_snapshot",
    "execution_record_id",
    "consumed_at",
    "execution_owner",
    "execution_key",
    "reconciliation_outcome",
    "reconciled_by",
    "reconciliation_note",
    "reconciliation_started_at",
    "reconciliation_completed_at",
    "reconciliation_attestation",
}

_APPROVAL_REQUIRED_FIELDS = {
    "action_id",
    "request_id",
    "tool_name",
    "target",
    "payload_hash",
    "authorization_hash",
    "payload_preview",
    "approval_scope",
    "reason",
    "created_at",
    "approval_id",
}

_APPROVAL_DEFAULTS: dict[str, Any] = {
    "policy_ids": [],
    "expires_at": "",
    "status": "pending",
    "decided_by": None,
    "decided_at": None,
    "note": "",
    "decision_attestation": None,
    "reserved_usd": "0",
    "action_snapshot": None,
    "request_snapshot": None,
    "decision_snapshot": None,
    "execution_record_id": "",
    "consumed_at": None,
    "execution_owner": "",
    "execution_key": "",
    "reconciliation_outcome": "",
    "reconciled_by": "",
    "reconciliation_note": "",
    "reconciliation_started_at": None,
    "reconciliation_completed_at": None,
    "reconciliation_attestation": None,
}

APPROVAL_STATUSES = {
    "pending",
    "approved",
    "rejected",
    "expired",
    "executing",
    "consumed",
}

RECONCILIATION_OUTCOMES = {
    "succeeded",
    "failed",
    "not_executed",
}


def _parse(ts: str) -> datetime:
    try:
        value = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ApprovalError(f"invalid approval timestamp: {ts!r}") from exc
    if value.tzinfo is None:
        raise ApprovalError("approval timestamps must be timezone-aware")
    return value


@dataclass(frozen=True, init=False)
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
    _policy_ids: Any = field(repr=False)
    expires_at: str = ""
    created_at: str = field(default_factory=utc_now)
    approval_id: str = field(default_factory=lambda: new_id("apr"))
    status: str = "pending"
    decided_by: str | None = None
    decided_at: str | None = None
    note: str = ""
    _decision_attestation: Any = field(repr=False)
    reserved_usd: str = "0"
    _action_snapshot: Any = field(repr=False)
    _request_snapshot: Any = field(repr=False)
    _decision_snapshot: Any = field(repr=False)
    execution_record_id: str = ""
    consumed_at: str | None = None
    execution_owner: str = ""
    execution_key: str = ""
    reconciliation_outcome: str = ""
    reconciled_by: str = ""
    reconciliation_note: str = ""
    reconciliation_started_at: str | None = None
    reconciliation_completed_at: str | None = None
    _reconciliation_attestation: Any = field(repr=False)

    def __init__(
        self,
        action_id: str,
        request_id: str,
        tool_name: str,
        target: str,
        payload_hash: str,
        authorization_hash: str,
        payload_preview: str,
        approval_scope: str,
        reason: str,
        policy_ids: list[str] | tuple[str, ...] | None = None,
        expires_at: str = "",
        created_at: str | None = None,
        approval_id: str | None = None,
        status: str = "pending",
        decided_by: str | None = None,
        decided_at: str | None = None,
        note: str = "",
        decision_attestation: dict[str, Any] | None = None,
        reserved_usd: MoneyLike = "0",
        action_snapshot: dict[str, Any] | None = None,
        request_snapshot: dict[str, Any] | None = None,
        decision_snapshot: dict[str, Any] | None = None,
        execution_record_id: str = "",
        consumed_at: str | None = None,
        execution_owner: str = "",
        execution_key: str = "",
        reconciliation_outcome: str = "",
        reconciled_by: str = "",
        reconciliation_note: str = "",
        reconciliation_started_at: str | None = None,
        reconciliation_completed_at: str | None = None,
        reconciliation_attestation: dict[str, Any] | None = None,
    ) -> None:
        validated = type(self).from_dict(
            {
                "action_id": action_id,
                "request_id": request_id,
                "tool_name": tool_name,
                "target": target,
                "payload_hash": payload_hash,
                "authorization_hash": authorization_hash,
                "payload_preview": payload_preview,
                "approval_scope": approval_scope,
                "reason": reason,
                "policy_ids": [] if policy_ids is None else policy_ids,
                "expires_at": expires_at,
                "created_at": utc_now() if created_at is None else created_at,
                "approval_id": new_id("apr") if approval_id is None else approval_id,
                "status": status,
                "decided_by": decided_by,
                "decided_at": decided_at,
                "note": note,
                "decision_attestation": decision_attestation,
                "reserved_usd": money_text(reserved_usd),
                "action_snapshot": action_snapshot,
                "request_snapshot": request_snapshot,
                "decision_snapshot": decision_snapshot,
                "execution_record_id": execution_record_id,
                "consumed_at": consumed_at,
                "execution_owner": execution_owner,
                "execution_key": execution_key,
                "reconciliation_outcome": reconciliation_outcome,
                "reconciled_by": reconciled_by,
                "reconciliation_note": reconciliation_note,
                "reconciliation_started_at": reconciliation_started_at,
                "reconciliation_completed_at": reconciliation_completed_at,
                "reconciliation_attestation": reconciliation_attestation,
            }
        )
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, getattr(validated, name))

    @property
    def policy_ids(self) -> list[str]:
        return thaw_snapshot(self._policy_ids)

    @property
    def decision_attestation(self) -> dict[str, Any] | None:
        return thaw_snapshot(self._decision_attestation)

    @property
    def action_snapshot(self) -> dict[str, Any] | None:
        return thaw_snapshot(self._action_snapshot)

    @property
    def request_snapshot(self) -> dict[str, Any] | None:
        return thaw_snapshot(self._request_snapshot)

    @property
    def decision_snapshot(self) -> dict[str, Any] | None:
        return thaw_snapshot(self._decision_snapshot)

    @property
    def reconciliation_attestation(self) -> dict[str, Any] | None:
        return thaw_snapshot(self._reconciliation_attestation)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PendingApproval":
        return cls._from_snapshot(_approval_snapshot(raw))

    @classmethod
    def _from_snapshot(cls, snapshot: dict[str, Any]) -> "PendingApproval":
        unknown = set(snapshot) - _APPROVAL_FIELDS
        missing = _APPROVAL_REQUIRED_FIELDS - set(snapshot)
        if unknown or missing:
            raise ApprovalError("approval fields do not match schema")
        values = {**_APPROVAL_DEFAULTS, **snapshot}

        for name in (
            "action_id",
            "request_id",
            "tool_name",
            "approval_id",
        ):
            if type(values[name]) is not str or not values[name]:
                raise ApprovalError(f"{name} must be non-empty")
        for name in (
            "target",
            "payload_hash",
            "authorization_hash",
            "payload_preview",
            "approval_scope",
            "reason",
            "expires_at",
            "note",
            "execution_record_id",
            "execution_owner",
            "execution_key",
            "reconciliation_outcome",
            "reconciled_by",
            "reconciliation_note",
        ):
            if type(values[name]) is not str:
                raise ApprovalError(f"{name} must be text")
        if values["decided_by"] is not None and type(values["decided_by"]) is not str:
            raise ApprovalError("decided_by must be text or null")
        if values["status"] not in APPROVAL_STATUSES:
            raise ApprovalError(f"invalid approval status: {values['status']}")
        policy_ids = values["policy_ids"]
        if type(policy_ids) is not list or any(
            type(policy_id) is not str or not policy_id for policy_id in policy_ids
        ):
            raise ApprovalError("policy_ids must be a list of non-empty strings")
        if bool(values["execution_owner"]) != bool(values["execution_key"]):
            raise ApprovalError(
                "execution_owner and execution_key must be supplied together"
            )

        if type(values["created_at"]) is not str:
            raise ApprovalError("created_at must be a timestamp")
        _parse(values["created_at"])
        if values["expires_at"]:
            _parse(values["expires_at"])
        for name in (
            "decided_at",
            "consumed_at",
            "reconciliation_started_at",
            "reconciliation_completed_at",
        ):
            value = values[name]
            if value is not None:
                if type(value) is not str:
                    raise ApprovalError(f"{name} must be a timestamp or null")
                _parse(value)
        status = values["status"]
        if status in {"approved", "executing", "consumed", "rejected"}:
            if not values["decided_by"] or not values["decided_at"]:
                raise ApprovalError(
                    f"{status} approval requires operator identity and decision time"
                )

        attestations: dict[str, dict[str, Any] | None] = {}
        for name in ("decision_attestation", "reconciliation_attestation"):
            value = values[name]
            if value is not None and type(value) is not dict:
                raise ApprovalError(f"{name} must be an object")
            attestations[name] = value
        if status in {"consumed", "rejected", "expired"} and not values["consumed_at"]:
            raise ApprovalError(f"{status} approval requires consumed_at")
        if status == "consumed" and not values["execution_record_id"]:
            raise ApprovalError("consumed approval requires execution evidence")

        reconciliation_values = (
            values["reconciliation_outcome"],
            values["reconciled_by"],
            values["reconciliation_note"],
            values["reconciliation_started_at"],
        )
        if any(reconciliation_values):
            if values["reconciliation_outcome"] not in RECONCILIATION_OUTCOMES:
                raise ApprovalError(
                    "invalid reconciliation outcome: "
                    f"{values['reconciliation_outcome']!r}"
                )
            if not values["reconciled_by"].strip():
                raise ApprovalError("reconciled_by must be non-empty")
            if not values["reconciliation_note"].strip():
                raise ApprovalError("reconciliation_note must be non-empty")
            if not values["reconciliation_started_at"]:
                raise ApprovalError("reconciliation_started_at must be present")
            if status not in {"executing", "consumed"}:
                raise ApprovalError(
                    "reconciliation intent requires executing or consumed status"
                )
        if values["reconciliation_completed_at"]:
            if not all(reconciliation_values):
                raise ApprovalError(
                    "completed reconciliation is missing its durable intent"
                )
            if status != "consumed" or not values["execution_record_id"]:
                raise ApprovalError(
                    "completed reconciliation requires consumed status and evidence"
                )
        elif status == "consumed" and values["reconciliation_outcome"]:
            raise ApprovalError("consumed reconciliation is missing completion time")

        action = _optional_contract_snapshot(
            values["action_snapshot"], ProposedAction.from_dict, "action_snapshot"
        )
        request = _optional_contract_snapshot(
            values["request_snapshot"], HarnessRequest.from_dict, "request_snapshot"
        )
        decision = _optional_contract_snapshot(
            values["decision_snapshot"],
            GuardrailDecision.from_dict,
            "decision_snapshot",
        )
        if action is not None:
            bindings = {
                "action_id": values["action_id"],
                "request_id": values["request_id"],
                "tool_name": values["tool_name"],
                "target": values["target"],
                "payload_hash": values["payload_hash"],
                "authorization_hash": values["authorization_hash"],
            }
            if any(action.get(name) != expected for name, expected in bindings.items()):
                raise ApprovalError("approval action snapshot binding is invalid")
        if request is not None and request.get("request_id") != values["request_id"]:
            raise ApprovalError("approval request snapshot binding is invalid")
        if action is not None and request is not None:
            if action.get("request_id") != request.get("request_id"):
                raise ApprovalError("approval action/request binding is invalid")
        if decision is not None:
            if (
                decision.get("reason") != values["reason"]
                or decision.get("approval_scope") != values["approval_scope"]
                or decision.get("policy_ids") != policy_ids
            ):
                raise ApprovalError("approval decision snapshot binding is invalid")

        approval = object.__new__(cls)
        private = {
            "policy_ids": "_policy_ids",
            "decision_attestation": "_decision_attestation",
            "action_snapshot": "_action_snapshot",
            "request_snapshot": "_request_snapshot",
            "decision_snapshot": "_decision_snapshot",
            "reconciliation_attestation": "_reconciliation_attestation",
        }
        for name in _APPROVAL_FIELDS:
            if name in private:
                object.__setattr__(
                    approval, private[name], freeze_snapshot(values[name])
                )
            elif name == "reserved_usd":
                object.__setattr__(
                    approval,
                    name,
                    money_text(money(values[name], field_name="reserved_usd")),
                )
            else:
                object.__setattr__(approval, name, values[name])
        object.__setattr__(approval, "_action_snapshot", freeze_snapshot(action))
        object.__setattr__(approval, "_request_snapshot", freeze_snapshot(request))
        object.__setattr__(approval, "_decision_snapshot", freeze_snapshot(decision))
        return approval

    def with_updates(self, **updates: Any) -> "PendingApproval":
        if set(updates) - _APPROVAL_FIELDS:
            raise ApprovalError("approval update fields do not match schema")
        raw = self.to_dict()
        raw.update(updates)
        return type(self).from_dict(raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "target": self.target,
            "payload_hash": self.payload_hash,
            "authorization_hash": self.authorization_hash,
            "payload_preview": self.payload_preview,
            "approval_scope": self.approval_scope,
            "reason": self.reason,
            "policy_ids": self.policy_ids,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "approval_id": self.approval_id,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "note": self.note,
            "decision_attestation": self.decision_attestation,
            "reserved_usd": self.reserved_usd,
            "action_snapshot": self.action_snapshot,
            "request_snapshot": self.request_snapshot,
            "decision_snapshot": self.decision_snapshot,
            "execution_record_id": self.execution_record_id,
            "consumed_at": self.consumed_at,
            "execution_owner": self.execution_owner,
            "execution_key": self.execution_key,
            "reconciliation_outcome": self.reconciliation_outcome,
            "reconciled_by": self.reconciled_by,
            "reconciliation_note": self.reconciliation_note,
            "reconciliation_started_at": self.reconciliation_started_at,
            "reconciliation_completed_at": self.reconciliation_completed_at,
            "reconciliation_attestation": self.reconciliation_attestation,
        }

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
    def __init__(
        self,
        path: str | Path,
        default_ttl_minutes: int = 60,
        operator_trust: OperatorTrustPolicy | None = None,
    ):
        if default_ttl_minutes <= 0:
            raise ValueError("default_ttl_minutes must be positive")
        self.path = Path(path)
        self.operator_trust = operator_trust
        prepare_storage_root(self.path.parent)
        self.default_ttl_minutes = default_ttl_minutes
        if not self.path.exists():
            with exclusive_file_lock(self.path):
                if not self.path.exists():
                    self._write_all({})
        self._read_all()

    # -- persistence --------------------------------------------------

    def _read_all(self) -> dict[str, PendingApproval]:
        try:
            data = _store_snapshot(read_json(self.path, max_bytes=_MAX_STATE_BYTES))
            approvals: dict[str, PendingApproval] = {}
            for approval_id, raw in data.items():
                if type(approval_id) is not str or not approval_id:
                    raise ApprovalError("approval key must be non-empty text")
                if type(raw) is not dict:
                    raise ApprovalError(f"approval {approval_id} is not an object")
                approval = PendingApproval._from_snapshot(raw)
                if approval.approval_id != approval_id:
                    raise ApprovalError(f"approval {approval_id} key mismatch")
                approvals[approval_id] = approval
            return approvals
        except ApprovalError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise ApprovalError(_error_detail(exc)) from exc

    def _write_all(self, data: dict[str, PendingApproval]) -> None:
        try:
            for approval_id, approval in data.items():
                if type(approval_id) is not str or not approval_id:
                    raise ApprovalError("approval key must be non-empty text")
                if type(approval) is not PendingApproval:
                    raise ApprovalError("approval store values must be sealed records")
                if approval.approval_id != approval_id:
                    raise ApprovalError(f"approval {approval_id} key mismatch")
            document = _store_snapshot(
                {
                    approval_id: approval.to_dict()
                    for approval_id, approval in data.items()
                }
            )
            atomic_write_json(self.path, document, max_bytes=_MAX_STATE_BYTES)
        except ApprovalError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise ApprovalError(_error_detail(exc)) from exc

    def _save(self, approval: PendingApproval) -> None:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            data[approval.approval_id] = approval
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
        execution_owner: str = "",
        execution_key: str = "",
    ) -> PendingApproval:
        pending = self.prepare(
            action,
            decision_reason,
            approval_scope,
            policy_ids,
            ttl_minutes,
            request=request,
            decision=decision,
            reserved_usd=reserved_usd,
            execution_owner=execution_owner,
            execution_key=execution_key,
        )
        return self.create_prepared(pending)

    def prepare(
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
        execution_owner: str = "",
        execution_key: str = "",
    ) -> PendingApproval:
        """Build an immutable approval snapshot without mutating the store."""
        ttl = ttl_minutes if ttl_minutes is not None else self.default_ttl_minutes
        if ttl <= 0:
            raise ApprovalError("approval TTL must be positive")
        expires = datetime.now(timezone.utc) + timedelta(minutes=ttl)
        action_snapshot = action.to_dict()
        request_snapshot = request.to_dict() if request else None
        decision_snapshot = decision.to_dict() if decision else None
        return PendingApproval(
            action_id=action_snapshot["action_id"],
            request_id=action_snapshot["request_id"],
            tool_name=action_snapshot["tool_name"],
            target=action_snapshot["target"],
            payload_hash=action_snapshot["payload_hash"],
            authorization_hash=action_snapshot["authorization_hash"],
            payload_preview=_preview(action_snapshot["payload"]),
            approval_scope=approval_scope,
            reason=decision_reason,
            policy_ids=policy_ids,
            expires_at=expires.isoformat().replace("+00:00", "Z"),
            reserved_usd=money_text(reserved_usd),
            action_snapshot=action_snapshot,
            request_snapshot=request_snapshot,
            decision_snapshot=decision_snapshot,
            execution_owner=execution_owner,
            execution_key=execution_key,
        )

    def create_prepared(self, pending: PendingApproval) -> PendingApproval:
        """Store one prepared approval idempotently or reject a conflict."""
        if type(pending) is not PendingApproval:
            raise ApprovalError("pending must be a sealed PendingApproval")
        with exclusive_file_lock(self.path):
            data = self._read_all()
            existing = data.get(pending.approval_id)
            if existing is not None:
                if existing.to_dict() == pending.to_dict():
                    return existing
                raise ApprovalError(
                    f"approval {pending.approval_id} conflicts with prepared state"
                )
            if any(
                approval.action_id == pending.action_id
                and approval.status in {"pending", "approved", "executing"}
                for approval in data.values()
            ):
                raise ApprovalError(
                    f"action {pending.action_id} already has an active approval"
                )
            data[pending.approval_id] = pending
            self._write_all(data)
        return pending

    def get(self, approval_id: str) -> PendingApproval | None:
        return self._read_all().get(approval_id)

    def for_action(self, action_id: str) -> list[PendingApproval]:
        return [
            approval
            for approval in self._read_all().values()
            if approval.action_id == action_id
        ]

    def list_pending(self) -> list[PendingApproval]:
        return sorted(
            (
                approval
                for approval in self._read_all().values()
                if approval.status == "pending" and not approval.is_expired()
            ),
            key=lambda approval: approval.created_at,
        )

    def list_actionable(self) -> list[PendingApproval]:
        return sorted(
            (
                approval
                for approval in self._read_all().values()
                if approval.status in {"pending", "approved", "executing"}
                and (approval.status == "executing" or not approval.is_expired())
            ),
            key=lambda approval: approval.created_at,
        )

    def find_execution(
        self,
        execution_owner: str,
        execution_key: str,
    ) -> PendingApproval | None:
        """Find an unconsumed exact-call approval owned by an external executor.

        An MCP proxy uses this to recognize a retried ``tools/call`` after the
        operator has approved it. Rejected calls remain terminal until their
        original approval window expires, preventing approval-spam retries.
        """
        if not execution_owner or not execution_key:
            return None
        matches = [
            approval
            for approval in self._read_all().values()
            if approval.execution_owner == execution_owner
            and approval.execution_key == execution_key
            and approval.status in {"pending", "approved", "rejected", "executing"}
        ]
        active = [
            approval
            for approval in matches
            if approval.status == "executing" or not approval.is_expired()
        ]
        return max(active, key=lambda approval: approval.created_at, default=None)

    def expire_due(self, now: datetime | None = None) -> list[PendingApproval]:
        expired: list[PendingApproval] = []
        with exclusive_file_lock(self.path):
            data = self._read_all()
            changed = False
            for approval_id, approval in data.items():
                if approval.status in {"pending", "approved"} and approval.is_expired(
                    now
                ):
                    approval = approval.with_updates(
                        status="expired", consumed_at=utc_now()
                    )
                    data[approval_id] = approval
                    expired.append(approval)
                    changed = True
            if changed:
                self._write_all(data)
        return expired

    def due(self, now: datetime | None = None) -> list[PendingApproval]:
        """Return due approvals without changing their state."""
        return sorted(
            (
                approval
                for approval in self._read_all().values()
                if approval.status in {"pending", "approved"}
                and approval.is_expired(now)
            ),
            key=lambda approval: approval.created_at,
        )

    def expire_one(self, approval_id: str) -> PendingApproval:
        """Expire exactly one due approval idempotently."""
        with exclusive_file_lock(self.path):
            data = self._read_all()
            approval = data.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if approval.status == "expired":
                return approval
            if approval.status not in {"pending", "approved"}:
                raise ApprovalError(
                    f"approval {approval_id} is already {approval.status}; cannot expire"
                )
            if not approval.is_expired():
                raise ApprovalError(f"approval {approval_id} is not due")
            approval = approval.with_updates(status="expired", consumed_at=utc_now())
            data[approval_id] = approval
            self._write_all(data)
            return approval

    def ensure_rejected(
        self,
        approval_id: str,
        decided_by: str,
        note: str,
        *,
        attestation: dict[str, Any] | None = None,
    ) -> PendingApproval:
        """Apply or recognize one exact rejection for journal recovery."""
        current = self.get(approval_id)
        if current is None:
            raise ApprovalError(f"unknown approval {approval_id}")
        if current.status == "pending":
            return self.decide(
                approval_id,
                False,
                decided_by,
                note,
                attestation=attestation,
            )
        if (
            current.status == "rejected"
            and current.decided_by == decided_by.strip()
            and current.note == note.strip()
            and current.decision_attestation == attestation
        ):
            self._require_decision_identity(current)
            return current
        raise ApprovalError(
            f"approval {approval_id} does not match the journaled rejection"
        )

    def decide(
        self,
        approval_id: str,
        approved: bool,
        decided_by: str,
        note: str = "",
        *,
        attestation: dict[str, Any] | None = None,
    ) -> PendingApproval:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            approval = data.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if approval.status != "pending":
                raise ApprovalError(
                    f"approval {approval_id} is already {approval.status}; "
                    "approvals are single-use"
                )
            if approval.is_expired():
                raise ApprovalError(
                    f"approval {approval_id} expired at {approval.expires_at}"
                )
            decided_by, note = self._validate_decision(
                approval, approved, decided_by, note, attestation
            )
            decided_at = (
                attestation["signed_at"] if attestation is not None else utc_now()
            )
            approval = approval.with_updates(
                status="approved" if approved else "rejected",
                decided_by=decided_by,
                decided_at=decided_at,
                note=note,
                decision_attestation=attestation,
                consumed_at=None if approved else decided_at,
            )
            data[approval_id] = approval
            self._write_all(data)
            return approval

    def validate_decision(
        self,
        approval_id: str,
        approved: bool,
        decided_by: str,
        note: str = "",
        *,
        attestation: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Validate one decision without mutating approval state."""
        approval = self.get(approval_id)
        if approval is None:
            raise ApprovalError(f"unknown approval {approval_id}")
        if approval.status != "pending":
            raise ApprovalError(
                f"approval {approval_id} is already {approval.status}; "
                "approvals are single-use"
            )
        if approval.is_expired():
            raise ApprovalError(
                f"approval {approval_id} expired at {approval.expires_at}"
            )
        return self._validate_decision(
            approval, approved, decided_by, note, attestation
        )

    def _validate_decision(
        self,
        approval: PendingApproval,
        approved: bool,
        decided_by: str,
        note: str,
        attestation: dict[str, Any] | None,
    ) -> tuple[str, str]:
        if not isinstance(decided_by, str) or not decided_by.strip():
            raise ApprovalError("decided_by must be non-empty")
        decided_by = decided_by.strip()
        note = note.strip()
        if attestation is not None and self.operator_trust is None:
            raise ApprovalError(
                "trusted operator keys are required to store an attestation"
            )
        if self.operator_trust is not None:
            try:
                self.operator_trust.require(
                    attestation,
                    approval,
                    purpose=DECISION_PURPOSE,
                    outcome="approved" if approved else "rejected",
                    operator=decided_by,
                    note=note,
                )
            except OperatorIdentityError as exc:
                raise ApprovalError(str(exc)) from exc
        return decided_by, note

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
        self._require_decision_identity(approval)
        return approval

    def begin_execution(
        self,
        approval_id: str,
        action: ProposedAction,
    ) -> PendingApproval:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            approval = data.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if approval.status != "approved":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executable"
                )
            if approval.is_expired():
                approval = approval.with_updates(
                    status="expired", consumed_at=utc_now()
                )
                data[approval_id] = approval
                self._write_all(data)
                raise ApprovalError(
                    f"approval {approval_id} expired at {approval.expires_at}"
                )
            if approval.action_id != action.action_id:
                raise ApprovalError("approval does not belong to this action")
            if approval.authorization_hash != action.authorization_hash:
                raise ApprovalError("action changed after approval")
            self._require_decision_identity(approval)
            approval = approval.with_updates(status="executing")
            data[approval_id] = approval
            self._write_all(data)
            return approval

    def mark_consumed(
        self,
        approval_id: str,
        execution_record_id: str,
    ) -> PendingApproval:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            approval = data.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if approval.status != "executing":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executing"
                )
            if approval.reconciliation_outcome:
                raise ApprovalError(
                    f"approval {approval_id} has operator reconciliation in progress"
                )
            approval = approval.with_updates(
                status="consumed",
                execution_record_id=execution_record_id,
                consumed_at=utc_now(),
            )
            data[approval_id] = approval
            self._write_all(data)
            return approval

    def ensure_consumed(
        self,
        approval_id: str,
        execution_record_id: str,
    ) -> PendingApproval:
        """Consume or recognize one exact journaled execution completion."""
        if not isinstance(execution_record_id, str) or not execution_record_id:
            raise ApprovalError("execution_record_id must be non-empty")
        with exclusive_file_lock(self.path):
            data = self._read_all()
            approval = data.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if approval.status == "consumed":
                if approval.execution_record_id != execution_record_id:
                    raise ApprovalError(
                        f"approval {approval_id} was consumed by different evidence"
                    )
                return approval
            if approval.status != "executing":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executing"
                )
            if approval.reconciliation_outcome:
                raise ApprovalError(
                    f"approval {approval_id} has operator reconciliation in progress"
                )
            approval = approval.with_updates(
                status="consumed",
                execution_record_id=execution_record_id,
                consumed_at=utc_now(),
            )
            data[approval_id] = approval
            self._write_all(data)
            return approval

    def begin_reconciliation(
        self,
        approval_id: str,
        outcome: str,
        reconciled_by: str,
        note: str,
        *,
        attestation: dict[str, Any] | None = None,
    ) -> PendingApproval:
        """Persist an idempotent operator decision before touching other stores."""
        if outcome not in RECONCILIATION_OUTCOMES:
            raise ApprovalError(
                "outcome must be one of: " + ", ".join(sorted(RECONCILIATION_OUTCOMES))
            )
        if not isinstance(reconciled_by, str) or not reconciled_by.strip():
            raise ApprovalError("reconciled_by must be non-empty")
        if not isinstance(note, str) or not note.strip():
            raise ApprovalError("reconciliation note must be non-empty")
        reconciled_by = reconciled_by.strip()
        note = note.strip()

        with exclusive_file_lock(self.path):
            data = self._read_all()
            approval = data.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            supplied = (outcome, reconciled_by, note)
            existing = (
                approval.reconciliation_outcome,
                approval.reconciled_by,
                approval.reconciliation_note,
            )
            if approval.reconciliation_outcome:
                if existing != supplied:
                    raise ApprovalError(
                        "reconciliation already started with different operator input"
                    )
                if approval.status not in {"executing", "consumed"}:
                    raise ApprovalError(
                        f"approval {approval_id} is {approval.status}, not reconcilable"
                    )
                if self.operator_trust is not None:
                    status = self.reconciliation_identity(approval)
                    if not status.ok:
                        raise ApprovalError(
                            "operator identity verification failed: " + status.detail
                        )
                return approval
            if approval.status != "executing":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executing"
                )
            if attestation is not None and self.operator_trust is None:
                raise ApprovalError(
                    "trusted operator keys are required to store an attestation"
                )
            if self.operator_trust is not None:
                try:
                    self.operator_trust.require(
                        attestation,
                        approval,
                        purpose=RECONCILIATION_PURPOSE,
                        outcome=outcome,
                        operator=reconciled_by,
                        note=note,
                    )
                except OperatorIdentityError as exc:
                    raise ApprovalError(str(exc)) from exc
            reconciliation_started_at = (
                attestation["signed_at"] if attestation is not None else utc_now()
            )
            approval = approval.with_updates(
                reconciliation_outcome=outcome,
                reconciled_by=reconciled_by,
                reconciliation_note=note,
                reconciliation_started_at=reconciliation_started_at,
                reconciliation_attestation=attestation,
            )
            data[approval_id] = approval
            self._write_all(data)
            return approval

    def decision_identity(self, approval: PendingApproval) -> OperatorIdentityStatus:
        if approval.decision_attestation is None:
            return unsigned_status(approval.decided_by or "")
        if self.operator_trust is None:
            return OperatorIdentityStatus(
                False,
                "unverified",
                "operator attestation is present but no trust pins were configured",
                operator=approval.decided_by or "",
                key_id=str(approval.decision_attestation.get("key_id", "")),
                signed_at=str(approval.decision_attestation.get("signed_at", "")),
            )
        return self.operator_trust.assess(
            approval.decision_attestation,
            approval,
            purpose=DECISION_PURPOSE,
            outcome="rejected" if approval.status == "rejected" else "approved",
            operator=approval.decided_by or "",
            note=approval.note,
        )

    def reconciliation_identity(
        self, approval: PendingApproval
    ) -> OperatorIdentityStatus:
        if approval.reconciliation_attestation is None:
            return unsigned_status(approval.reconciled_by)
        if self.operator_trust is None:
            return OperatorIdentityStatus(
                False,
                "unverified",
                "reconciliation attestation is present but no trust pins were configured",
                operator=approval.reconciled_by,
                key_id=str(approval.reconciliation_attestation.get("key_id", "")),
                signed_at=str(approval.reconciliation_attestation.get("signed_at", "")),
            )
        return self.operator_trust.assess(
            approval.reconciliation_attestation,
            approval,
            purpose=RECONCILIATION_PURPOSE,
            outcome=approval.reconciliation_outcome,
            operator=approval.reconciled_by,
            note=approval.reconciliation_note,
        )

    def _require_decision_identity(self, approval: PendingApproval) -> None:
        if self.operator_trust is None:
            return
        status = self.decision_identity(approval)
        if not status.ok:
            raise ApprovalError(
                f"operator identity verification failed: {status.detail}"
            )

    def mark_reconciled(
        self,
        approval_id: str,
        execution_record_id: str,
    ) -> PendingApproval:
        if not isinstance(execution_record_id, str) or not execution_record_id:
            raise ApprovalError("execution_record_id must be non-empty")
        with exclusive_file_lock(self.path):
            data = self._read_all()
            approval = data.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if not approval.reconciliation_outcome:
                raise ApprovalError(
                    f"approval {approval_id} has no operator reconciliation intent"
                )
            if approval.status == "consumed":
                if approval.execution_record_id != execution_record_id:
                    raise ApprovalError(
                        "reconciled approval is bound to a different evidence record"
                    )
                return approval
            if approval.status != "executing":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executing"
                )
            consumed_at = utc_now()
            approval = approval.with_updates(
                status="consumed",
                execution_record_id=execution_record_id,
                consumed_at=consumed_at,
                reconciliation_completed_at=consumed_at,
            )
            data[approval_id] = approval
            self._write_all(data)
            return approval


def _preview(payload: dict, limit: int = 400) -> str:
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


def _approval_snapshot(value: Any) -> dict[str, Any]:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value,
            maximum_canonical_bytes=_MAX_STATE_BYTES,
        )
    except ValueError as exc:
        raise ApprovalError("approval exceeds bounded canonical contract") from exc
    if type(snapshot) is not dict:
        raise ApprovalError("approval must be an object")
    return snapshot


def _store_snapshot(value: Any) -> dict[str, Any]:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value,
            maximum_canonical_bytes=_MAX_STATE_BYTES,
        )
    except ValueError as exc:
        raise ApprovalError(
            "approval state exceeds bounded canonical contract"
        ) from exc
    if type(snapshot) is not dict:
        raise ApprovalError("approval state must be an object")
    return snapshot


def _optional_contract_snapshot(value: Any, loader, field_name: str):
    if value is None:
        return None
    if type(value) is not dict:
        raise ApprovalError(f"{field_name} must be an object")
    try:
        normalized = loader(value).to_dict()
    except (KeyError, TypeError, ValueError) as exc:
        raise ApprovalError(f"{field_name} is invalid") from exc
    if normalized != value:
        raise ApprovalError(f"{field_name} is not canonical")
    return normalized


def _error_detail(exc: BaseException) -> str:
    detail = str(exc).strip()
    return detail or type(exc).__name__
