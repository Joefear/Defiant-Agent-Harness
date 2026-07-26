"""Small fail-closed persistence helpers used by local state stores."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4


class PersistenceError(RuntimeError):
    """Local state could not be read or mutated safely."""


@contextmanager
def exclusive_file_lock(target: str | Path) -> Iterator[None]:
    """Acquire a conservative cross-process lock for one state file.

    Lock contention fails immediately instead of waiting or proceeding
    concurrently. If a process crashes, the lock file remains intentionally:
    an operator must confirm no writer is alive before removing it.
    """
    path = Path(target)
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(lock_path, flags, 0o600)
    except FileExistsError as exc:
        raise PersistenceError(
            f"state file is locked: {path}. Refusing concurrent or uncertain write"
        ) from exc
    try:
        os.write(fd, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(fd)
        yield
    finally:
        os.close(fd)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def read_json(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        with open(source, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PersistenceError(
            f"cannot read valid JSON state from {source}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise PersistenceError(f"state root must be a JSON object: {source}")
    return data


def atomic_write_json(path: str | Path, data: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    try:
        with open(tmp, "x", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True, allow_nan=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, destination)
    except (OSError, TypeError, ValueError) as exc:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise PersistenceError(
            f"cannot atomically write state to {destination}: {exc}"
        ) from exc
