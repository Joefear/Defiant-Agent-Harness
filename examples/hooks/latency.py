"""Opt-in, offline measurement of the real hook entrypoint in disposable state.

Run from the repository root: python examples/hooks/latency.py --output report.json
This does not emulate the host runner or override its fail-open timeout.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
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
    except (ValueError, TypeError, KeyError):
        outcome = "invalid_response"
    if result.returncode != 0:
        outcome = "process_error"
    reason = (
        response.get("reason", "") if isinstance(locals().get("response"), dict) else ""
    )
    reason += result.stderr
    busy = "authority transaction is busy" in reason or "state file is locked" in reason
    return {"seconds": elapsed, "outcome": outcome, "busy_refusal": busy}


def measure(kind: str, *, rounds: int, workers: int, history_pairs: int) -> dict:
    gate_type = CodexHookGate if kind == "codex" else CopilotHookGate
    with tempfile.TemporaryDirectory(prefix="dah-s6-latency-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        state = root / "state"
        gate = gate_type(workspace, state)
        for _ in range(history_pairs):
            sample = event(workspace)
            gate.pre_tool_use(sample)
            gate.post_tool_use(sample | {"tool_response": "synthetic"})
        environment = {k: v for k, v in os.environ.items() if not k.startswith("DAH_")}
        environment["DAH_HOOK_WORKDIR"] = str(state)
        environment["DAH_CODEX_HOOK_WORKDIR"] = str(state)
        # Preserve the selected interpreter's dependency path, adding this source.
        source = str(Path(__file__).resolve().parents[2] / "src")
        environment["PYTHONPATH"] = (
            source + os.pathsep + environment.get("PYTHONPATH", "")
        )
        cases = []
        for mode in ("serial", "concurrent", "held_authority_lock"):
            count = 1 if mode == "serial" else workers
            for phase in ("pre", "post"):
                observations = []
                for _ in range(rounds):
                    documents = [event(workspace) for _ in range(count)]
                    if phase == "post":
                        for sample in documents:
                            gate.pre_tool_use(sample)
                            sample["tool_response"] = "synthetic"
                    before = gate.harness.evidence.path.read_bytes()
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
                                    invoke,
                                    kind,
                                    phase,
                                    sample,
                                    workspace,
                                    environment,
                                    barrier,
                                )
                                for sample in documents
                            ]
                            batch = [future.result() for future in futures]
                    if mode == "held_authority_lock":
                        assert gate.harness.evidence.path.read_bytes() == before
                    observations.extend(batch)
                durations = sorted(item["seconds"] for item in observations)
                expected = "allow" if phase == "pre" else "sealed"
                correct = all(
                    item["outcome"] == expected
                    if mode == "serial"
                    else (item["outcome"] == "refused" and item["busy_refusal"])
                    if mode == "held_authority_lock"
                    else (
                        item["outcome"] == expected
                        or (item["outcome"] == "refused" and item["busy_refusal"])
                    )
                    for item in observations
                )
                cases.append(
                    {
                        "mode": mode,
                        "phase": phase,
                        "workers": count,
                        "samples": len(observations),
                        "min_seconds": durations[0],
                        "max_seconds": durations[-1],
                        "margin_seconds": BUDGET_SECONDS - durations[-1],
                        "responses_valid": correct,
                        "within_budget": durations[-1] < BUDGET_SECONDS
                        and all(item["outcome"] != "timeout" for item in observations),
                        "observations": observations,
                    }
                )
        assert gate.harness.evidence.verify().ok
        return {
            "hook": kind,
            "initial_history_records": history_pairs * 2,
            "final_history_records": len(gate.harness.evidence.records()),
            "cases": cases,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--history-pairs", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if (
        not 1 <= args.rounds <= 100
        or not 2 <= args.workers <= 16
        or not 0 <= args.history_pairs <= 1000
    ):
        parser.error("rounds 1..100, workers 2..16, history-pairs 0..1000 required")
    report = {
        "schema": "defiant.hook_latency.v1",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "budget_seconds": BUDGET_SECONDS,
        "scope": "Python entrypoint subprocess startup, hook work, output and exit; excludes runner and shell wrapper; synthetic local state, no network or real tool execution",
        "hooks": [
            measure(
                kind,
                rounds=args.rounds,
                workers=args.workers,
                history_pairs=args.history_pairs,
            )
            for kind in ("codex", "copilot")
        ],
    }
    report["passed"] = all(
        case["responses_valid"] and case["within_budget"]
        for hook in report["hooks"]
        for case in hook["cases"]
    )
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "output": str(args.output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
