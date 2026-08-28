"""Durable correlation between pre-tool authorization and post-tool evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..contracts import (
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    authority_snapshot_and_sha256_of,
    utc_now,
)
from ..frozen_snapshot import freeze_snapshot, thaw_snapshot
from ..limits import MAX_HOOK_EXECUTION_STATE_BYTES
from ..persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    prepare_storage_root,
    read_json,
)

_MAX_STATE_BYTES = MAX_HOOK_EXECUTION_STATE_BYTES
_EXECUTION_FIELDS = {
    "tool_use_id",
    "execution_key",
    "native_tool_name",
    "action_snapshot",
    "request_snapshot",
    "decision_snapshot",
    "authorization_record_id",
    "approval_id",
    "status",
    "completion_record_id",
    "created_at",
    "completed_at",
}


class HookStateError(RuntimeError):
    """Hook execution state cannot be trusted or updated safely."""


@dataclass(frozen=True, init=False)
class HookExecution:
    tool_use_id: str
    execution_key: str
    native_tool_name: str
    _action_snapshot: Any = field(repr=False)
    _request_snapshot: Any = field(repr=False)
    _decision_snapshot: Any = field(repr=False)
    authorization_record_id: str
    approval_id: str = ""
    status: str = "authorized"
    completion_record_id: str = ""
    created_at: str = ""
    completed_at: str | None = None

    def __init__(
        self,
        tool_use_id: str,
        execution_key: str,
        native_tool_name: str,
        action_snapshot: dict[str, Any],
        request_snapshot: dict[str, Any],
        decision_snapshot: dict[str, Any],
        authorization_record_id: str,
        approval_id: str = "",
        status: str = "authorized",
        completion_record_id: str = "",
        created_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        validated = type(self).from_dict(
            {
                "tool_use_id": tool_use_id,
                "execution_key": execution_key,
                "native_tool_name": native_tool_name,
                "action_snapshot": action_snapshot,
                "request_snapshot": request_snapshot,
                "decision_snapshot": decision_snapshot,
                "authorization_record_id": authorization_record_id,
                "approval_id": approval_id,
                "status": status,
                "completion_record_id": completion_record_id,
                "created_at": utc_now() if created_at is None else created_at,
                "completed_at": completed_at,
            }
        )
        for name in (
            "tool_use_id",
            "execution_key",
            "native_tool_name",
            "_action_snapshot",
            "_request_snapshot",
            "_decision_snapshot",
            "authorization_record_id",
            "approval_id",
            "status",
            "completion_record_id",
            "created_at",
            "completed_at",
        ):
            object.__setattr__(self, name, getattr(validated, name))

    @property
    def action_snapshot(self) -> dict[str, Any]:
        return _projection(self._action_snapshot, "action_snapshot")

    @property
    def request_snapshot(self) -> dict[str, Any]:
        return _projection(self._request_snapshot, "request_snapshot")

    @property
    def decision_snapshot(self) -> dict[str, Any]:
        return _projection(self._decision_snapshot, "decision_snapshot")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "HookExecution":
        return cls._from_snapshot(_execution_snapshot(raw))

    @classmethod
    def _from_snapshot(cls, snapshot: dict[str, Any]) -> "HookExecution":
        if set(snapshot) != _EXECUTION_FIELDS:
            raise HookStateError("hook execution fields do not match schema")
        for name in (
            "tool_use_id",
            "execution_key",
            "native_tool_name",
            "authorization_record_id",
        ):
            value = snapshot.get(name)
            if type(value) is not str or not value:
                raise HookStateError(f"{name} must be non-empty")
        approval_id = snapshot.get("approval_id")
        completion_record_id = snapshot.get("completion_record_id")
        if type(approval_id) is not str or type(completion_record_id) is not str:
            raise HookStateError("hook execution identifiers must be text")
        status = snapshot.get("status")
        if status not in {"authorized", "completed"}:
            raise HookStateError("invalid hook execution status")
        if status == "completed" and not completion_record_id:
            raise HookStateError("completed hook execution needs a record id")
        if status == "authorized" and completion_record_id:
            raise HookStateError("authorized hook execution cannot have completion")
        created_at = _timestamp(snapshot.get("created_at"), "created_at")
        completed_at = snapshot.get("completed_at")
        if completed_at is not None:
            completed_at = _timestamp(completed_at, "completed_at")
        if status == "authorized" and completed_at is not None:
            raise HookStateError("authorized hook execution cannot be completed")
        if status == "completed" and completed_at is None:
            raise HookStateError("completed hook execution needs a completion time")

        action = _contract_snapshot(
            snapshot.get("action_snapshot"),
            ProposedAction.from_dict,
            "action_snapshot",
        )
        request = _contract_snapshot(
            snapshot.get("request_snapshot"),
            HarnessRequest.from_dict,
            "request_snapshot",
        )
        decision = _contract_snapshot(
            snapshot.get("decision_snapshot"),
            GuardrailDecision.from_dict,
            "decision_snapshot",
        )
        if action.get("request_id") != request.get("request_id"):
            raise HookStateError("hook execution action/request binding is invalid")
        execution = object.__new__(cls)
        for name in (
            "tool_use_id",
            "execution_key",
            "native_tool_name",
            "authorization_record_id",
        ):
            object.__setattr__(execution, name, snapshot[name])
        object.__setattr__(execution, "_action_snapshot", freeze_snapshot(action))
        object.__setattr__(execution, "_request_snapshot", freeze_snapshot(request))
        object.__setattr__(execution, "_decision_snapshot", freeze_snapshot(decision))
        object.__setattr__(execution, "approval_id", approval_id)
        object.__setattr__(execution, "status", status)
        object.__setattr__(execution, "completion_record_id", completion_record_id)
        object.__setattr__(execution, "created_at", created_at)
        object.__setattr__(execution, "completed_at", completed_at)
        return execution

    def complete(
        self, completion_record_id: str, *, completed_at: str
    ) -> "HookExecution":
        if type(completion_record_id) is not str or not completion_record_id:
            raise HookStateError("completion_record_id must be non-empty")
        snapshot = self.to_dict()
        snapshot.update(
            status="completed",
            completion_record_id=completion_record_id,
            completed_at=completed_at,
        )
        return type(self).from_dict(snapshot)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_use_id": self.tool_use_id,
            "execution_key": self.execution_key,
            "native_tool_name": self.native_tool_name,
            "action_snapshot": self.action_snapshot,
            "request_snapshot": self.request_snapshot,
            "decision_snapshot": self.decision_snapshot,
            "authorization_record_id": self.authorization_record_id,
            "approval_id": self.approval_id,
            "status": self.status,
            "completion_record_id": self.completion_record_id,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class HookExecutionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        prepare_storage_root(self.path.parent)
        if not self.path.exists():
            with exclusive_file_lock(self.path):
                if not self.path.exists():
                    self._write_all({})
        self._read_all()

    def _read_all(self) -> dict[str, HookExecution]:
        try:
            data = _store_snapshot(read_json(self.path, max_bytes=_MAX_STATE_BYTES))
            executions: dict[str, HookExecution] = {}
            for tool_use_id, raw in data.items():
                if type(tool_use_id) is not str or not tool_use_id:
                    raise HookStateError("hook execution key must be non-empty text")
                if type(raw) is not dict:
                    raise HookStateError("hook execution record must be an object")
                execution = HookExecution._from_snapshot(raw)
                if execution.tool_use_id != tool_use_id:
                    raise HookStateError("hook execution key mismatch")
                executions[tool_use_id] = execution
            return executions
        except HookStateError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise HookStateError(_error_detail(exc)) from exc

    def _write_all(self, data: dict[str, HookExecution]) -> None:
        try:
            document = _store_snapshot(
                {
                    tool_use_id: execution.to_dict()
                    for tool_use_id, execution in data.items()
                }
            )
            atomic_write_json(
                self.path,
                document,
                max_bytes=_MAX_STATE_BYTES,
            )
        except HookStateError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise HookStateError(_error_detail(exc)) from exc

    def get(self, tool_use_id: str) -> HookExecution | None:
        return self._read_all().get(tool_use_id)

    def create(self, execution: HookExecution) -> HookExecution:
        if not isinstance(execution, HookExecution):
            raise HookStateError("execution must be a sealed HookExecution")
        with exclusive_file_lock(self.path):
            data = self._read_all()
            existing = data.get(execution.tool_use_id)
            if existing is not None:
                prior = existing
                if (
                    prior.execution_key == execution.execution_key
                    and prior.authorization_record_id
                    == execution.authorization_record_id
                ):
                    return prior
                if (
                    prior.status == "completed"
                    and prior.execution_key == execution.execution_key
                ):
                    data[execution.tool_use_id] = execution
                    self._write_all(data)
                    return execution
                raise HookStateError(
                    f"tool_use_id {execution.tool_use_id} was already authorized"
                )
            data[execution.tool_use_id] = execution
            self._write_all(data)
        return execution

    def mark_completed(
        self,
        tool_use_id: str,
        completion_record_id: str,
    ) -> HookExecution:
        if not completion_record_id:
            raise HookStateError("completion_record_id must be non-empty")
        with exclusive_file_lock(self.path):
            data = self._read_all()
            execution = data.get(tool_use_id)
            if execution is None:
                raise HookStateError(f"unknown tool_use_id {tool_use_id}")
            if execution.status == "completed":
                if execution.completion_record_id != completion_record_id:
                    raise HookStateError(
                        f"tool_use_id {tool_use_id} has a different completion"
                    )
                return execution
            execution = execution.complete(
                completion_record_id,
                completed_at=utc_now(),
            )
            data[tool_use_id] = execution
            self._write_all(data)
        return execution


def _execution_snapshot(value: Any) -> dict[str, Any]:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value,
            maximum_canonical_bytes=_MAX_STATE_BYTES,
        )
    except ValueError as exc:
        raise HookStateError(
            "hook execution exceeds bounded canonical contract"
        ) from exc
    if type(snapshot) is not dict:
        raise HookStateError("hook execution must be an object")
    return snapshot


def _store_snapshot(value: Any) -> dict[str, Any]:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value,
            maximum_canonical_bytes=_MAX_STATE_BYTES,
        )
    except ValueError as exc:
        raise HookStateError(
            "hook execution state exceeds bounded canonical contract"
        ) from exc
    if type(snapshot) is not dict:
        raise HookStateError("hook execution state must be an object")
    return snapshot


def _contract_snapshot(value: Any, loader, field_name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HookStateError(f"{field_name} must be an object")
    try:
        normalized = loader(value).to_dict()
    except (KeyError, TypeError, ValueError) as exc:
        raise HookStateError(f"{field_name} is invalid") from exc
    if normalized != value:
        raise HookStateError(f"{field_name} is not canonical")
    return normalized


def _projection(value: Any, field_name: str) -> dict[str, Any]:
    projection = thaw_snapshot(value)
    if type(projection) is not dict:
        raise RuntimeError(f"sealed {field_name} root is invalid")
    return projection


def _timestamp(value: Any, field_name: str) -> str:
    if type(value) is not str or not value:
        raise HookStateError(f"{field_name} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HookStateError(f"{field_name} must be a timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HookStateError(f"{field_name} must include a timezone")
    return value


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return str(exc)
