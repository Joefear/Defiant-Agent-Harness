"""Small fail-closed persistence helpers used by local state stores."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from threading import Lock, RLock, local
from typing import Any, Iterator
from uuid import uuid4


class PersistenceError(RuntimeError):
    """Local state could not be read or mutated safely."""


class AuthorityLockError(PersistenceError):
    """Another process or thread owns the state directory's authority gate."""


_AUTHORITY_LOCKS_GUARD = Lock()
_AUTHORITY_LOCKS: dict[Path, RLock] = {}
_AUTHORITY_ACTIVE_FDS: set[int] = set()
_AUTHORITY_DEPTHS = local()


def _authority_before_fork() -> None:
    _AUTHORITY_LOCKS_GUARD.acquire()


def _authority_after_fork_parent() -> None:
    _AUTHORITY_LOCKS_GUARD.release()


def _authority_after_fork_child() -> None:
    global _AUTHORITY_ACTIVE_FDS
    global _AUTHORITY_DEPTHS
    global _AUTHORITY_LOCKS
    global _AUTHORITY_LOCKS_GUARD
    for fd in _AUTHORITY_ACTIVE_FDS:
        try:
            os.close(fd)
        except OSError:
            pass
    _AUTHORITY_ACTIVE_FDS = set()
    _AUTHORITY_LOCKS = {}
    _AUTHORITY_DEPTHS = local()
    _AUTHORITY_LOCKS_GUARD = Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_authority_before_fork,
        after_in_parent=_authority_after_fork_parent,
        after_in_child=_authority_after_fork_child,
    )


def _process_authority_lock(path: Path) -> RLock:
    with _AUTHORITY_LOCKS_GUARD:
        return _AUTHORITY_LOCKS.setdefault(path, RLock())


def _lock_byte(fd: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_byte(fd: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


class AuthorityTransactionLock:
    """Crash-released, reentrant, nonblocking lock for one state directory."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        self._process_lock = _process_authority_lock(self.path)

    @contextmanager
    def acquire(self) -> Iterator[None]:
        if not self._process_lock.acquire(blocking=False):
            raise AuthorityLockError(
                f"authority transaction is busy for state directory: {self.path.parent}"
            )
        depths = getattr(_AUTHORITY_DEPTHS, "paths", None)
        if depths is None:
            depths = {}
            _AUTHORITY_DEPTHS.paths = depths
        depth = depths.get(self.path, 0)
        if depth:
            depths[self.path] = depth + 1
            try:
                yield
            finally:
                depths[self.path] -= 1
                self._process_lock.release()
            return

        self.path.parent.mkdir(parents=True, exist_ok=True)
        locked = False
        fd = -1
        try:
            with _AUTHORITY_LOCKS_GUARD:
                flags = os.O_CREAT | os.O_RDWR
                try:
                    fd = os.open(self.path, flags, 0o600)
                except OSError as exc:
                    raise AuthorityLockError(
                        f"cannot open authority transaction lock {self.path}: {exc}"
                    ) from exc
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                    os.fsync(fd)
                try:
                    _lock_byte(fd)
                except OSError as exc:
                    raise AuthorityLockError(
                        "authority transaction is busy for state directory: "
                        f"{self.path.parent}"
                    ) from exc
                locked = True
                _AUTHORITY_ACTIVE_FDS.add(fd)
            depths[self.path] = 1
            try:
                yield
            finally:
                depths.pop(self.path, None)
        finally:
            with _AUTHORITY_LOCKS_GUARD:
                if locked:
                    try:
                        _unlock_byte(fd)
                    except OSError:
                        pass
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    _AUTHORITY_ACTIVE_FDS.discard(fd)
            self._process_lock.release()


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
