"""Opt-in, offline measurement of the real hook entrypoint in disposable state.

Run from the repository root: python examples/hooks/latency.py --output report.json
This does not emulate the host runner or override its fail-open timeout.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from defiant_agent_harness.hooks.codex import CodexHookGate
from defiant_agent_harness.hooks.copilot import CopilotHookGate
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.store import GENESIS
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

BUDGET_SECONDS = 10.0


def event(workspace: Path) -> dict:
    return {
        "session_id": "s6-latency",
        "cwd": str(workspace),
        "tool_name": "Read",
        "tool_input": {"file_path": "synthetic.txt"},
        "tool_use_id": uuid.uuid4().hex,
    }


def invoke(kind, phase, document, workspace, environment, barrier):
    barrier.wait(timeout=30)
    started = time.perf_counter()
    command = [
        sys.executable,
        "-c",
        f"from defiant_agent_harness.hooks.{kind} import main; raise SystemExit(main())",
        phase,
    ]
    try:
        result = subprocess.run(
            command,
            input=json.dumps(document),
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=workspace,
            env=environment,
            timeout=BUDGET_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"seconds": time.perf_counter() - started, "outcome": "timeout"}
    elapsed = time.perf_counter() - started
    try:
        response = json.loads(result.stdout)
        if phase == "pre":
            decision = response["hookSpecificOutput"]["permissionDecision"]
            outcome = {"allow": "allow", "deny": "refused"}[decision]
        else:
            if response.get("decision") == "block":
                outcome = "refused"
            elif (
                "Defiant sealed" in response["hookSpecificOutput"]["additionalContext"]
            ):
                outcome = "sealed"
            else:
                outcome = "invalid_response"
    except (ValueError, TypeError, KeyError, AttributeError):
        outcome = "invalid_response"
    if result.returncode != 0:
        outcome = "process_error"
    reason = (
        response.get("reason", "") if isinstance(locals().get("response"), dict) else ""
    )
    reason = str(reason) + result.stderr
    busy = "authority transaction is busy" in reason or "state file is locked" in reason
    return {"seconds": elapsed, "outcome": outcome, "busy_refusal": busy}


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    if path.exists():
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
    return digest.hexdigest()


def seed_history(gate, count: int) -> None:
    """Bulk-create synthetic terminal history only in this fresh benchmark root.

    Avoid quadratic fixture preparation through repeated append/audit. Measured
    entrypoints still perform every normal authority check on the resulting state.
    """
    store = gate.harness.evidence
    records = store.records()
    previous = records[-1]["record_hash"] if records else GENESIS
    with store.path.open("a", encoding="utf-8", newline="\n") as stream:
        for index in range(count):
            record = EvidenceRecord(
                request_id=f"synthetic-history-request-{index}",
                action_id=f"synthetic-history-action-{index}",
                decision=Decision.BLOCK,
                result_status=ResultStatus.BLOCKED,
                enforcement_basis="native_hook_preview",
                result_summary="Synthetic terminal history; no native tool executed",
            ).seal(previous)
            stream.write(json.dumps(record.to_dict()) + "\n")
            previous = record.record_hash
        stream.flush()
        os.fsync(stream.fileno())
    store._reconcile_head()


def inspect_state(state: Path) -> dict:
    # authority.lock is the normal persistent OS-lock backing file, not a stale
    # exclusive-create sentinel. Existence alone says nothing about ownership.
    locks = sorted(p.name for p in state.glob("*.lock"))
    return {
        "audit": StateIntegrityAuditor(state).audit().to_dict(),
        "lock_files": locks,
        "sentinel_lock_files": [name for name in locks if name != "authority.lock"],
    }


def measure(
    kind: str,
    *,
    rounds: int,
    workers: int,
    history_records: int,
    mode: str,
    phase: str,
    fixture_parent: Path,
) -> dict:
    # Retain EVERY fixture, not just timeouts, so a failed/deadline-killed case
    # can never be silently discarded or repaired before independent inspection.
    root = Path(tempfile.mkdtemp(prefix=f"{kind}-{mode}-{phase}-", dir=fixture_parent))
    workspace = root / "workspace"
    workspace.mkdir()
    state = root / "state"
    result = {
        "hook": kind,
        "mode": mode,
        "phase": phase,
        "seed_history_records": history_records,
        "fixture_root": str(root),
        "fixture_retained": True,
        "observations": [],
        "responses_valid": False,
        "within_budget": False,
    }
    try:
        gate_type = CodexHookGate if kind == "codex" else CopilotHookGate
        gate = gate_type(workspace, state)
        count = 1 if mode == "serial" else workers
        batches = [[event(workspace) for _ in range(count)] for _ in range(rounds)]
        # Prepare matched post events before large-history seeding, outside the
        # timer. All history is present for each measured production entrypoint.
        if phase == "post":
            for batch in batches:
                for sample in batch:
                    response = gate.pre_tool_use(sample)
                    if response["hookSpecificOutput"]["permissionDecision"] != "allow":
                        raise RuntimeError("post fixture preflight was not allowed")
                    sample["tool_response"] = "synthetic"
        seed_history(gate, history_records)
        result["initial_history_records"] = len(gate.harness.evidence.records())
        result["initial_history_bytes"] = gate.harness.evidence.path.stat().st_size
        result["initial_state"] = inspect_state(state)
        if not result["initial_state"]["audit"]["safe_to_execute"]:
            raise RuntimeError("unsafe seed fixture")
        environment = {k: v for k, v in os.environ.items() if not k.startswith("DAH_")}
        environment["DAH_HOOK_WORKDIR"] = str(state)
        environment["DAH_CODEX_HOOK_WORKDIR"] = str(state)
        source = str(Path(__file__).resolve().parents[2] / "src")
        environment["PYTHONPATH"] = (
            source + os.pathsep + environment.get("PYTHONPATH", "")
        )
        unchanged = True
        for documents in batches:
            before = fingerprint(gate.harness.evidence.path)
            lock = (
                gate.harness.authority_lock.acquire()
                if mode == "held_authority_lock"
                else nullcontext()
            )
            with lock:
                barrier = threading.Barrier(count)
                with ThreadPoolExecutor(max_workers=count) as pool:
                    futures = [
                        pool.submit(
                            invoke, kind, phase, sample, workspace, environment, barrier
                        )
                        for sample in documents
                    ]
                    batch = [future.result() for future in futures]
            result["observations"].extend(batch)
            if mode == "held_authority_lock":
                unchanged &= fingerprint(gate.harness.evidence.path) == before
            # Do not continue mutating a deadline-killed fixture. Other cases get
            # independent roots, so a stale lock cannot skew their measurements.
            if any(item["outcome"] == "timeout" for item in batch):
                break
        observations = result["observations"]
        durations = [item["seconds"] for item in observations]
        expected = "allow" if phase == "pre" else "sealed"
        correct = all(
            item["outcome"] == expected
            if mode == "serial"
            else (item["outcome"] == "refused" and item.get("busy_refusal", False))
            if mode == "held_authority_lock"
            else (
                item["outcome"] == expected
                or (item["outcome"] == "refused" and item.get("busy_refusal", False))
            )
            for item in observations
        )
        result.update(
            {
                "workers": count,
                "requested_samples": rounds * count,
                "samples": len(observations),
                "min_seconds": min(durations),
                "max_seconds": max(durations),
                "margin_seconds_upper_bound": BUDGET_SECONDS - max(durations),
                "responses_valid": correct
                and unchanged
                and len(observations) == rounds * count,
                "within_budget": max(durations) < BUDGET_SECONDS
                and all(item["outcome"] != "timeout" for item in observations),
                "held_lock_evidence_unchanged": unchanged
                if mode == "held_authority_lock"
                else None,
            }
        )
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        # Include cross-store consistency and stale sentinels, not just hashes.
        try:
            result["final_state"] = inspect_state(state)
        except Exception as error:
            result["final_state"] = {
                "audit_error": f"{type(error).__name__}: {error}",
                "lock_files": sorted(p.name for p in state.glob("*.lock")),
            }
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--workers", type=int, default=4)
    history = parser.add_mutually_exclusive_group()
    history.add_argument("--history-records", type=int, nargs="+")
    history.add_argument(
        "--history-pairs",
        type=int,
        help="legacy count alias; seeds twice this many terminal records",
    )
    parser.add_argument(
        "--hooks", nargs="+", choices=("codex", "copilot"), default=["codex", "copilot"]
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=("serial", "concurrent", "held_authority_lock"),
        default=["serial", "concurrent", "held_authority_lock"],
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    sizes = (
        args.history_records
        if args.history_records is not None
        else (
            [args.history_pairs * 2]
            if args.history_pairs is not None
            else [20, 2000, 20000]
        )
    )
    if (
        not 1 <= args.rounds <= 100
        or not 2 <= args.workers <= 16
        or any(not 0 <= size <= 200000 for size in sizes)
    ):
        parser.error("rounds 1..100, workers 2..16, history records 0..200000 required")
    if args.output.exists():
        parser.error("output exists; use a new path to preserve every run")
    args.output = args.output.resolve()
    fixture_parent = Path(
        tempfile.mkdtemp(prefix="s6-latency-fixtures-", dir=args.output.parent)
    )
    report = {
        "schema": "defiant.hook_latency.v2",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "budget_seconds": BUDGET_SECONDS,
        "scope": "Python entrypoint startup/work/output/exit and timeout cleanup; excludes shell wrapper and host runner; margins are upper bounds; synthetic terminal history, no network or real tool execution",
        "fixture_parent": str(fixture_parent),
        "complete": False,
        "cases": [],
    }

    def save():
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    save()
    for size in sizes:
        for kind in args.hooks:
            for mode in args.modes:
                for phase in ("pre", "post"):
                    case = measure(
                        kind,
                        rounds=args.rounds,
                        workers=args.workers,
                        history_records=size,
                        mode=mode,
                        phase=phase,
                        fixture_parent=fixture_parent,
                    )
                    report["cases"].append(case)
                    save()
                    print(
                        json.dumps(
                            {
                                key: case.get(key)
                                for key in (
                                    "hook",
                                    "mode",
                                    "phase",
                                    "initial_history_records",
                                    "max_seconds",
                                    "within_budget",
                                    "error",
                                )
                            }
                        ),
                        flush=True,
                    )
    report["complete"] = True
    report["passed"] = all(
        case["responses_valid"]
        and case["within_budget"]
        and case["final_state"].get("audit", {}).get("safe_to_execute", False)
        and not case["final_state"].get("sentinel_lock_files", [])
        for case in report["cases"]
    )
    save()
    print(json.dumps({"passed": report["passed"], "output": str(args.output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
