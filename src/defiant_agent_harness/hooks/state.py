"""Durable correlation between pre-tool authorization and post-tool evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..contracts import utc_now
from ..persistence import (
    atomic_write_json,
    exclusive_file_lock,
    prepare_storage_root,
    read_json,
)


class HookStateError(RuntimeError):
    """Hook execution state cannot be trusted or updated safely."""


@dataclass
class HookExecution:
    tool_use_id: str
    execution_key: str
    native_tool_name: str
    action_snapshot: dict[str, Any]
    request_snapshot: dict[str, Any]
    decision_snapshot: dict[str, Any]
    authorization_record_id: str
    approval_id: str = ""
    status: str = "authorized"
    completion_record_id: str = ""
    created_at: str = field(default_factory=utc_now)
    completed_at: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "tool_use_id",
            "execution_key",
            "native_tool_name",
            "authorization_record_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise HookStateError(f"{name} must be non-empty")
        for name in ("action_snapshot", "request_snapshot", "decision_snapshot"):
            if not isinstance(getattr(self, name), dict):
                raise HookStateError(f"{name} must be an object")
        if self.status not in {"authorized", "completed"}:
            raise HookStateError(f"invalid hook execution status: {self.status}")
        if self.status == "completed" and not self.completion_record_id:
            raise HookStateError("completed hook execution needs a record id")


class HookExecutionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        prepare_storage_root(self.path.parent)
        if not self.path.exists():
            with exclusive_file_lock(self.path):
                if not self.path.exists():
                    atomic_write_json(self.path, {})
        self._read_all()

    def _read_all(self) -> dict[str, dict[str, Any]]:
        data = read_json(self.path)
        for tool_use_id, raw in data.items():
            if not isinstance(raw, dict):
                raise HookStateError(f"hook execution {tool_use_id} is not an object")
            execution = HookExecution(**raw)
            if execution.tool_use_id != tool_use_id:
                raise HookStateError(f"hook execution key mismatch for {tool_use_id}")
        return data

    def get(self, tool_use_id: str) -> HookExecution | None:
        raw = self._read_all().get(tool_use_id)
        return HookExecution(**raw) if raw else None

    def create(self, execution: HookExecution) -> HookExecution:
        with exclusive_file_lock(self.path):
            data = self._read_all()
            existing = data.get(execution.tool_use_id)
            if existing is not None:
                prior = HookExecution(**existing)
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
                    data[execution.tool_use_id] = asdict(execution)
                    atomic_write_json(self.path, data)
                    return execution
                raise HookStateError(
                    f"tool_use_id {execution.tool_use_id} was already authorized"
                )
            data[execution.tool_use_id] = asdict(execution)
            atomic_write_json(self.path, data)
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
            raw = data.get(tool_use_id)
            if raw is None:
                raise HookStateError(f"unknown tool_use_id {tool_use_id}")
            execution = HookExecution(**raw)
            if execution.status == "completed":
                if execution.completion_record_id != completion_record_id:
                    raise HookStateError(
                        f"tool_use_id {tool_use_id} has a different completion"
                    )
                return execution
            execution.status = "completed"
            execution.completion_record_id = completion_record_id
            execution.completed_at = utc_now()
            data[tool_use_id] = asdict(execution)
            atomic_write_json(self.path, data)
        return execution
