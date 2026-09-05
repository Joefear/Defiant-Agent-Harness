"""Small fail-closed persistence helpers used by local state stores."""

from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock, RLock, local
from typing import Any, IO, Iterator
from uuid import uuid4

from .limits import MAX_DURABLE_JSON_BYTES
from .strict_json import loads_strict_json


class PersistenceError(RuntimeError):
    """Local state could not be read or mutated safely."""


class AuthorityLockError(PersistenceError):
    """Another process or thread owns the state directory's authority gate."""


@dataclass(frozen=True)
class StorageRootObservation:
    """Canonical identity and platform posture for one state directory."""

    path: Path
    identity: tuple[int, int]
    private_permissions: bool | None
    directory_sync: str


_AUTHORITY_LOCKS_GUARD = Lock()
_AUTHORITY_LOCKS: dict[Path, RLock] = {}
_AUTHORITY_ACTIVE_FDS: set[int] = set()
_AUTHORITY_DEPTHS = local()


def prepare_storage_root(path: str | Path) -> StorageRootObservation:
    """Create or validate a canonical private state directory."""
    root = Path(os.path.abspath(path))
    try:
        current = os.lstat(root)
    except FileNotFoundError:
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=False)
            _sync_directory(root.parent)
        except FileExistsError:
            pass
        except OSError as exc:
            raise PersistenceError(
                f"cannot create state directory: {_os_detail(exc)}"
            ) from exc
        try:
            current = os.lstat(root)
        except OSError as exc:
            raise PersistenceError(
                f"cannot inspect state directory: {_os_detail(exc)}"
            ) from exc
    except OSError as exc:
        raise PersistenceError(
            f"cannot inspect state directory: {_os_detail(exc)}"
        ) from exc
    return _storage_root_observation(root, current)


def inspect_storage_root(path: str | Path) -> StorageRootObservation | None:
    """Read one state-directory posture without creating or changing it."""
    root = Path(os.path.abspath(path))
    try:
        current = os.lstat(root)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PersistenceError(
            f"cannot inspect state directory: {_os_detail(exc)}"
        ) from exc
    return _storage_root_observation(root, current)


def require_storage_root_unchanged(observation: StorageRootObservation) -> None:
    """Refuse a state-root replacement after authority inputs were resolved."""
    try:
        current = os.lstat(observation.path)
    except OSError as exc:
        raise PersistenceError(
            "state directory changed or disappeared after verification"
        ) from exc
    checked = _storage_root_observation(observation.path, current)
    if checked.identity != observation.identity:
        raise PersistenceError("state directory identity changed after verification")


def inspect_state_file(path: str | Path) -> os.stat_result | None:
    """Validate that a durable state path is private and has no indirection."""
    source = Path(path)
    root = inspect_storage_root(source.parent)
    if root is None:
        raise PersistenceError("state directory does not exist")
    try:
        current = os.lstat(source)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PersistenceError(
            f"cannot inspect state file {_state_name(source)}: {_os_detail(exc)}"
        ) from exc
    _validate_state_file_stat(source, current)
    return current


@contextmanager
def open_state_file(
    path: str | Path,
    mode: str,
    *,
    encoding: str | None = None,
) -> Iterator[IO[Any]]:
    """Open a state file without following indirection or accepting replacement."""
    source = Path(path)
    modes = {
        "r": os.O_RDONLY,
        "rb": os.O_RDONLY,
        "ab": os.O_WRONLY | os.O_APPEND,
        "x": os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        "xb": os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    }
    if mode not in modes:
        raise ValueError(f"unsupported secure state-file mode: {mode}")
    exclusive = "x" in mode
    if exclusive:
        root = prepare_storage_root(source.parent)
    else:
        root = inspect_storage_root(source.parent)
        if root is None:
            raise PersistenceError("state directory does not exist")
    before = None if exclusive else inspect_state_file(source)
    if not exclusive and before is None:
        raise PersistenceError(f"state file does not exist: {_state_name(source)}")
    flags = modes[mode] | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(source, flags, 0o600)
    except OSError as exc:
        raise PersistenceError(
            f"cannot safely open state file {_state_name(source)}: {_os_detail(exc)}"
        ) from exc
    try:
        after = os.fstat(fd)
        _validate_state_file_stat(source, after)
        if before is not None and _identity(before) != _identity(after):
            raise PersistenceError(
                f"state file changed while opening: {_state_name(source)}"
            )
        require_storage_root_unchanged(root)
        kwargs = {"encoding": encoding} if "b" not in mode else {}
        with os.fdopen(fd, mode, **kwargs) as handle:
            fd = -1
            opened_identity = _identity(after)
            try:
                yield handle
            finally:
                final = os.fstat(handle.fileno())
                _validate_state_file_stat(source, final)
                current = inspect_state_file(source)
                if (
                    current is None
                    or _identity(current) != opened_identity
                    or _identity(final) != opened_identity
                ):
                    raise PersistenceError(
                        f"state file changed while open: {_state_name(source)}"
                    )
                require_storage_root_unchanged(root)
    finally:
        if fd >= 0:
            os.close(fd)


def sync_storage_directory(path: str | Path) -> None:
    """Durably publish a state-directory entry where the platform supports it."""
    _sync_directory(Path(path))


def _storage_root_observation(
    root: Path, current: os.stat_result
) -> StorageRootObservation:
    if stat.S_ISLNK(current.st_mode) or _is_reparse_point(current):
        raise PersistenceError("state directory must not be a symlink or reparse point")
    if not stat.S_ISDIR(current.st_mode):
        raise PersistenceError("state root must be a directory")
    private = _private_permissions(current, directory=True)
    try:
        canonical = root.resolve(strict=True)
    except OSError as exc:
        raise PersistenceError(
            f"cannot resolve state directory: {_os_detail(exc)}"
        ) from exc
    return StorageRootObservation(
        path=canonical,
        identity=_identity(current),
        private_permissions=private,
        directory_sync="required" if os.name == "posix" else "best_effort",
    )


def _validate_state_file_stat(path: Path, current: os.stat_result) -> None:
    if stat.S_ISLNK(current.st_mode) or _is_reparse_point(current):
        raise PersistenceError(
            f"state file must not be a symlink or reparse point: {_state_name(path)}"
        )
    if not stat.S_ISREG(current.st_mode):
        raise PersistenceError(f"state file must be regular: {_state_name(path)}")
    if current.st_nlink != 1:
        raise PersistenceError(
            f"state file must have exactly one hard link: {_state_name(path)}"
        )
    _private_permissions(current, directory=False)


def _private_permissions(current: os.stat_result, *, directory: bool) -> bool | None:
    if os.name != "posix" or not hasattr(os, "geteuid"):
        return None
    if current.st_uid != os.geteuid():
        kind = "directory" if directory else "file"
        raise PersistenceError(f"state {kind} must be owned by the current user")
    kind = "directory" if directory else "file"
    required_mode = 0o700 if directory else 0o600
    if stat.S_IMODE(current.st_mode) != required_mode:
        required = f"0{required_mode:o}"
        raise PersistenceError(f"state {kind} permissions must be private ({required})")
    return True


def _identity(current: os.stat_result) -> tuple[int, int]:
    return current.st_dev, current.st_ino


def _state_name(path: str | Path) -> str:
    return Path(path).name or "state-root"


def _os_detail(exc: OSError) -> str:
    return exc.strerror or exc.__class__.__name__


def _is_reparse_point(current: os.stat_result) -> bool:
    attributes = getattr(current, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & marker)


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if os.name == "nt":
            return
        raise PersistenceError(
            f"cannot open state directory for sync: {_os_detail(exc)}"
        ) from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        if os.name != "nt":
            raise PersistenceError(
                f"cannot sync state directory: {_os_detail(exc)}"
            ) from exc
    finally:
        os.close(fd)


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
        self.path = Path(os.path.abspath(path))
        self._process_lock = _process_authority_lock(self.path)

    @contextmanager
    def acquire(self) -> Iterator[None]:
        if not self._process_lock.acquire(blocking=False):
            raise AuthorityLockError(
                "authority transaction is busy for state directory"
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

        root = prepare_storage_root(self.path.parent)
        locked = False
        fd = -1
        try:
            with _AUTHORITY_LOCKS_GUARD:
                before = inspect_state_file(self.path)
                flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                try:
                    fd = os.open(self.path, flags, 0o600)
                except OSError as exc:
                    raise AuthorityLockError(
                        f"cannot open authority transaction lock: {_os_detail(exc)}"
                    ) from exc
                after = os.fstat(fd)
                _validate_state_file_stat(self.path, after)
                if before is not None and _identity(before) != _identity(after):
                    raise AuthorityLockError(
                        "authority transaction lock changed while opening"
                    )
                require_storage_root_unchanged(root)
                if after.st_size == 0:
                    os.write(fd, b"\0")
                    os.fsync(fd)
                    sync_storage_directory(root.path)
                try:
                    _lock_byte(fd)
                except OSError as exc:
                    raise AuthorityLockError(
                        "authority transaction is busy for state directory"
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
def exclusive_file_lock(
    target: str | Path, *, require_existing_root: bool = False
) -> Iterator[None]:
    """Acquire a conservative cross-process lock for one state file.

    Lock contention fails immediately instead of waiting or proceeding
    concurrently. If a process crashes, the lock file remains intentionally:
    an operator must confirm no writer is alive before removing it.
    Existing-only callers may refuse directory initialization while retaining
    the same conservative lock lifecycle.
    """
    path = Path(target)
    lock_path = path.with_name(path.name + ".lock")
    root = (
        inspect_storage_root(path.parent)
        if require_existing_root
        else prepare_storage_root(path.parent)
    )
    if root is None:
        raise PersistenceError("state directory does not exist")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except FileExistsError as exc:
        raise PersistenceError(
            f"state file is locked: {_state_name(path)}. "
            "Refusing concurrent or uncertain write"
        ) from exc
    except OSError as exc:
        raise PersistenceError(f"cannot create state lock: {_os_detail(exc)}") from exc
    lock_identity = _identity(os.fstat(fd))
    try:
        _validate_state_file_stat(lock_path, os.fstat(fd))
        os.write(fd, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(fd)
        require_storage_root_unchanged(root)
        sync_storage_directory(root.path)
        yield
    finally:
        os.close(fd)
        try:
            current = inspect_state_file(lock_path)
            if current is None or _identity(current) != lock_identity:
                raise PersistenceError(
                    "state lock changed while held; refusing removal: "
                    f"{_state_name(lock_path)}"
                )
            lock_path.unlink()
            sync_storage_directory(root.path)
        except FileNotFoundError:
            pass


def read_json(
    path: str | Path,
    *,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    source = Path(path)
    maximum = MAX_DURABLE_JSON_BYTES if max_bytes is None else max_bytes
    if type(maximum) is not int or maximum < 1:
        raise ValueError("JSON state byte ceiling must be a positive integer")
    try:
        with open_state_file(source, "rb") as fh:
            encoded = fh.read(maximum + 1)
        if len(encoded) > maximum:
            raise PersistenceError(
                f"state file exceeds {maximum} bytes: {_state_name(source)}"
            )
        data = loads_strict_json(encoded, label="state JSON")
    except PersistenceError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise PersistenceError(
            f"cannot read valid JSON state from {_state_name(source)}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise PersistenceError(
            f"state file must contain a JSON object: {_state_name(source)}"
        )
    return data


def atomic_write_json(
    path: str | Path,
    data: dict[str, Any],
    *,
    max_bytes: int | None = None,
) -> None:
    maximum = MAX_DURABLE_JSON_BYTES if max_bytes is None else max_bytes
    if type(maximum) is not int or maximum < 1:
        raise ValueError("JSON state byte ceiling must be a positive integer")
    destination = Path(path)
    root = prepare_storage_root(destination.parent)
    before = inspect_state_file(destination)
    tmp = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    try:
        with open_state_file(tmp, "x", encoding="utf-8") as fh:
            bounded = _BoundedTextWriter(fh, maximum)
            json.dump(data, bounded, indent=2, sort_keys=True, allow_nan=False)
            fh.flush()
            os.fsync(fh.fileno())
        inspect_state_file(tmp)
        require_storage_root_unchanged(root)
        current = inspect_state_file(destination)
        if (before is None) != (current is None) or (
            before is not None
            and current is not None
            and _identity(before) != _identity(current)
        ):
            raise PersistenceError(
                "state file changed before atomic replacement: "
                f"{_state_name(destination)}"
            )
        os.replace(tmp, destination)
        inspect_state_file(destination)
        sync_storage_directory(root.path)
    except (OSError, TypeError, ValueError) as exc:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise PersistenceError(
            f"cannot atomically write state to {_state_name(destination)}: "
            f"{_os_detail(exc) if isinstance(exc, OSError) else exc}"
        ) from exc


class _BoundedTextWriter:
    def __init__(self, handle: IO[str], maximum: int):
        self.handle = handle
        self.maximum = maximum
        self.written = 0

    def write(self, value: str) -> int:
        encoded = len(value.encode("utf-8"))
        if self.written + encoded > self.maximum:
            raise ValueError(f"JSON state exceeds {self.maximum} bytes")
        self.written += encoded
        return self.handle.write(value)
