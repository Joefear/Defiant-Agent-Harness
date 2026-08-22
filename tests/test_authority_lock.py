from __future__ import annotations

import os
import subprocess
import sys
import threading
from decimal import Decimal

import pytest

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.contracts import HarnessRequest, SideEffect
from defiant_agent_harness.orchestrator.harness import Harness, build_harness
from defiant_agent_harness.persistence import (
    AuthorityLockError,
    AuthorityTransactionLock,
)
from defiant_agent_harness.tools.registry import ToolRegistry, ToolResult, ToolSpec


def _request(label: str) -> HarnessRequest:
    return HarnessRequest(
        task=label,
        user_id="operator",
        workspace_id="workspace",
    )


@pytest.mark.parametrize(
    "name",
    [
        "run",
        "handle_call",
        "preflight_external_call",
        "resume_external",
        "complete_external_call",
        "resume",
        "reconcile_expired_approvals",
        "reconcile_execution",
        "reconcile_authorization",
        "recover_operation",
    ],
)
def test_every_public_authority_entrypoint_is_locked(name):
    assert hasattr(getattr(Harness, name), "__wrapped__")


def test_authority_lock_is_reentrant_across_instances(tmp_path):
    path = tmp_path / "state" / "authority.lock"

    with AuthorityTransactionLock(path).acquire():
        with AuthorityTransactionLock(path).acquire():
            assert path.exists()

    assert path.read_bytes() == b"\0"


def test_authority_lock_refuses_another_thread_without_waiting(tmp_path):
    path = tmp_path / "state" / "authority.lock"
    acquired = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    def hold_lock():
        try:
            with AuthorityTransactionLock(path).acquire():
                acquired.set()
                assert release.wait(timeout=10)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert acquired.wait(timeout=10)
    try:
        with pytest.raises(AuthorityLockError, match="authority transaction is busy"):
            with AuthorityTransactionLock(path).acquire():
                pytest.fail("contending thread acquired authority")
    finally:
        release.set()
        holder.join(timeout=10)

    assert not holder.is_alive()
    assert failures == []


def test_authority_lock_is_cross_process_and_released_after_crash(tmp_path):
    path = tmp_path / "state" / "authority.lock"
    script = (
        "import sys\n"
        "from defiant_agent_harness.persistence import AuthorityTransactionLock\n"
        "with AuthorityTransactionLock(sys.argv[1]).acquire():\n"
        "    print('locked', flush=True)\n"
        "    sys.stdin.readline()\n"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(AuthorityLockError, match="authority transaction is busy"):
            with AuthorityTransactionLock(path).acquire():
                pytest.fail("contending process acquired authority")
    finally:
        child.kill()
        child.wait(timeout=10)

    with AuthorityTransactionLock(path).acquire():
        pass


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_forked_child_does_not_inherit_reentrant_authority(tmp_path):
    path = tmp_path / "state" / "authority.lock"

    with AuthorityTransactionLock(path).acquire():
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - exercised by the child process
            try:
                with AuthorityTransactionLock(path).acquire():
                    os._exit(2)
            except AuthorityLockError:
                os._exit(0)
        _, status = os.waitpid(child_pid, 0)

    assert os.waitstatus_to_exitcode(status) == 0


def test_build_harness_refuses_authority_contention_before_store_creation(tmp_path):
    state = tmp_path / "state"
    lock = AuthorityTransactionLock(state / "authority.lock")
    acquired = threading.Event()
    release = threading.Event()

    def hold_lock():
        with lock.acquire():
            acquired.set()
            assert release.wait(timeout=10)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert acquired.wait(timeout=10)
    try:
        with pytest.raises(AuthorityLockError, match="authority transaction is busy"):
            build_harness(state, MockAgentAdapter())
    finally:
        release.set()
        holder.join(timeout=10)

    assert not holder.is_alive()
    assert not (state / "evidence.jsonl").exists()
    assert not (state / "approvals.json").exists()
    assert not (state / "budget.json").exists()


def test_harnesses_cannot_interleave_while_a_tool_is_executing(tmp_path):
    state = tmp_path / "state"
    entered = threading.Event()
    release = threading.Event()
    first_calls = {"count": 0}
    second_calls = {"count": 0}

    first_registry = ToolRegistry()

    def slow_tool(_action):
        first_calls["count"] += 1
        entered.set()
        assert release.wait(timeout=10)
        return ToolResult(
            status="succeeded",
            summary="slow result",
            output={"ok": True},
            cost_usd=Decimal("0"),
        )

    first_registry.register(
        ToolSpec("summarize", SideEffect.NONE, "Slow fixture."), slow_tool
    )
    second_registry = ToolRegistry()

    def forbidden_tool(_action):
        second_calls["count"] += 1
        return ToolResult(status="succeeded", summary="must not execute")

    second_registry.register(
        ToolSpec("summarize", SideEffect.NONE, "Second fixture."), forbidden_tool
    )
    first = build_harness(
        state,
        MockAgentAdapter(),
        tools=first_registry,
    )
    second = build_harness(
        state,
        MockAgentAdapter(),
        tools=second_registry,
    )
    failures: list[BaseException] = []

    def execute_first():
        try:
            first.handle_call(
                ToolCall(name="summarize", arguments={"text": "first"}),
                _request("first"),
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    worker = threading.Thread(target=execute_first)
    worker.start()
    assert entered.wait(timeout=10)
    try:
        with pytest.raises(AuthorityLockError, match="authority transaction is busy"):
            second.handle_call(
                ToolCall(name="summarize", arguments={"text": "second"}),
                _request("second"),
            )
    finally:
        release.set()
        worker.join(timeout=10)

    assert not worker.is_alive()
    assert failures == []
    assert first_calls["count"] == 1
    assert second_calls["count"] == 0
    assert len(first.evidence.records()) == 2
