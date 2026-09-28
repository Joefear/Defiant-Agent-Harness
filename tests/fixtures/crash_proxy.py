"""Test-only barriers around the real CLI; parent must kill this interpreter.

No production crash switch, fabricated response, or recovery replacement.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

from defiant_agent_harness.evidence import store as evidence_module
from defiant_agent_harness.mcp.session import UpstreamSession
from defiant_agent_harness.operation_journal import OperationJournal


def install_barrier(point: str, marker: Path) -> None:
    def stop():
        temporary = marker.with_suffix(".tmp")
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump({"pid": os.getpid(), "point": point}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, marker)
        if not threading.Event().wait(120):
            raise RuntimeError("parent failed to kill the proxy at its barrier")

    original_call = UpstreamSession.call_tool

    def call(self, name, arguments, **kwargs):
        if name == "write_file" and point == "before_dispatch":
            stop()
        result = original_call(self, name, arguments, **kwargs)
        if name == "write_file" and point == "before_journal":
            assert result.status == "succeeded", result
            stop()
        return result

    UpstreamSession.call_tool = call
    original_prepare = OperationJournal.prepare

    def prepare(self, kind, payload):
        operation = original_prepare(self, kind, payload)
        if kind == "execution_complete" and point == "after_journal":
            stop()
        return operation

    OperationJournal.prepare = prepare
    original_open = evidence_module.open_state_file

    class TornAppend:
        def __init__(self, handle):
            self.handle = handle

        def write(self, data):
            record = json.loads(data)
            if record["result_status"] == "succeeded":
                # Split the actual serialized append, not a later corruption.
                self.handle.write(data[: len(data) // 2])
                self.handle.flush()
                os.fsync(self.handle.fileno())
                stop()
            return self.handle.write(data)

        def __getattr__(self, name):
            return getattr(self.handle, name)

    @contextmanager
    def opened(path, mode, **kwargs):
        with original_open(path, mode, **kwargs) as handle:
            yield (
                TornAppend(handle)
                if point == "during_append" and mode == "ab"
                else handle
            )

    evidence_module.open_state_file = opened


if __name__ == "__main__":
    point, marker, *arguments = sys.argv[1:]
    install_barrier(point, Path(marker))
    from defiant_agent_harness.cli.main import main

    raise SystemExit(main(arguments))
